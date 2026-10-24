"""Generated native callers exercise named callback contracts and failure paths."""
import json,struct,tempfile,unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver
from tests.test_kernel_process import process_probe
from tests.test_kernel_system_information import image_range

MODES=('create','missing','system-power','system-time','system-processor','reopen',
       'case-sensitive','case-insensitive','unnamed','malformed-name','security','root','readonly',
       'register','duplicate','multiple','unregister','unregister-twice','register-invalid',
       'notify-empty','notify-active','notify-system','dereference','reopen-deleted','permanent',
       'body-read','body-write','body-call','api-read','api-write','token-read',
       'registration-holds-reference','irql-create','irql-register','irql-unregister','irql-notify',
       'bad-length','odd-unicode','short-unicode')
PARTIAL={'security','root','readonly','unregister-twice','notify-active','notify-system',
         'body-read','body-write','body-call','api-read','api-write','token-read',
         'irql-create','irql-register','irql-unregister','irql-notify'}
EXPORTS=('ExCreateCallback','ExRegisterCallback','ExUnregisterCallback','ExNotifyCallback')


def named_callback_probe(machine,mode):
    wide=machine==0x8664;base,width=(0x140000000,8) if wide else (0x400000,4)
    rex=b'\x48' if wide else b''
    pointer=lambda n:n.to_bytes(width,'little')
    load=lambda rva:rex+b'\xa1'+pointer(base+rva)
    store=lambda rva:rex+b'\xa3'+pointer(base+rva)
    name={'system-power':r'\Callback\PowerState','system-time':r'\Callback\SetSystemTime',
          'system-processor':r'\Callback\ProcessorAdd','notify-system':r'\Callback\PowerState'}.get(mode,r'\Callback\EmumeeFixture')
    if mode=='malformed-name':name+='\0tail'
    text=name.encode('utf-16le')
    flags=0x40 | (0x10 if mode=='permanent' else 0)
    def attributes(name_pointer):
        return (struct.pack('<I',48)+bytes(4)+pointer(1 if mode=='root' else 0)+pointer(name_pointer)+
                struct.pack('<I',flags)+bytes(4)+pointer(base+0x2400 if mode=='security' else 0)+pointer(0)) if wide else (
                struct.pack('<I',24)+pointer(1 if mode=='root' else 0)+pointer(name_pointer)+
                struct.pack('<I',flags)+pointer(base+0x2400 if mode=='security' else 0)+pointer(0))
    writes=[(0x2400,attributes(0 if mode=='unnamed' else base+0x2440)),
            (0x2440,struct.pack('<HH',len(text),len(text)+2)+(bytes(4) if wide else b'')+pointer(base+0x2480)),
            (0x2480,text+bytes(2)),(0x23c0,'fixture\0'.encode('utf-16le'))]
    if mode=='bad-length':writes.append((0x2400,struct.pack('<I',4)))
    if mode=='odd-unicode':writes.append((0x2440,struct.pack('<H',len(text)-1)))
    if mode=='short-unicode':writes.append((0x2442,struct.pack('<H',len(text)-2)))
    names=[*EXPORTS,'ObDereferenceObject','RtlCompareMemory','RtlInitUnicodeString','KfRaiseIrql']
    operations=[('raw',b'\xb8COLD'+store(0x23f8))]
    def raise_irql(level):
        if wide:operations.append((7,[level],None))
        else:operations.append(('raw',b'\xb9'+struct.pack('<I',level)+b'\xff\x15'+pointer(base+0x2900+7*width)))
    def dereference():
        if wide:operations.append((4,[('load',0x2300)],None))
        else:operations.append(('raw',load(0x2300)+b'\x89\xc1\xff\x15'+pointer(base+0x2900+4*width)))
    if mode=='irql-create':raise_irql(2)
    create=mode not in ('missing','system-power','system-time','system-processor','notify-system')
    output=base+(0x1100 if mode=='readonly' else 0x2300)
    operations.append((0,[output,base+0x2400,int(create),int(mode=='multiple')],0x2310))
    if mode in ('reopen','case-sensitive','case-insensitive'):
        if mode.startswith('case-'):
            other=(name[:10]+name[10:].lower()).encode('utf-16le')
            writes.extend([(0x2a00,attributes(base+0x2a40)),
                (0x2a40,struct.pack('<HH',len(other),len(other)+2)+(bytes(4) if wide else b'')+pointer(base+0x2a80)),
                (0x2a80,other+bytes(2))])
            if mode=='case-sensitive':
                blob=bytearray(writes[-3][1]);struct.pack_into('<I',blob,24 if wide else 12,0)
                writes[-3]=(0x2a00,bytes(blob))
        operations.append((0,[base+0x2320,base+(0x2a00 if mode.startswith('case-') else 0x2400),0,0],0x2328))
    registration_modes={'register','duplicate','multiple','unregister','unregister-twice',
                        'register-invalid','notify-active','token-read','registration-holds-reference',
                        'irql-register','irql-unregister'}
    if mode in registration_modes:
        if mode=='irql-register':raise_irql(2)
        operations.append((1,[('load',0x2300),base+(0x23c0 if mode=='register-invalid' else 0x1180),0x1234],0x2330))
        if mode in ('duplicate','multiple'):
            operations.append((1,[('load',0x2300),base+0x1180,0x5678],0x2338))
        if mode=='registration-holds-reference':dereference()
        if mode=='irql-unregister':raise_irql(2)
        if mode in ('unregister','unregister-twice','registration-holds-reference','irql-unregister'):
            operations.append((2,[('load',0x2330)],None))
            if mode=='unregister-twice':operations.append((2,[('load',0x2330)],None))
    if mode=='irql-notify':raise_irql(3)
    if mode.startswith('notify-') or mode=='irql-notify':
        operations.append((3,[('load',0x2300),0x1111,0x2222],None))
    if mode in ('dereference','reopen-deleted','permanent'):
        dereference()
        if mode!='dereference':
            operations.append((0,[base+0x2320,base+0x2400,0,0],0x2328))
    if mode.startswith('body-') or mode=='token-read':
        operations.append(('raw',load(0x2330 if mode=='token-read' else 0x2300)+
            (rex+b'\x8b\x00' if mode in ('body-read','token-read') else b'\xc7\x00FAIL' if mode=='body-write' else b'\xff\xd0')))
    if mode=='api-read':operations.append((5,[('load',0x2300),base+0x23b0,8],None))
    if mode=='api-write':operations.append((6,[('load',0x2300),base+0x23c0],None))
    operations.append(('raw',b'\xb8DONE'+store(0x23f8)+b'\x31\xc0'))
    data=bytearray(call_driver(machine,names,operations,writes=writes))
    # A registration must not invent an event or execute this routine.
    data[0x380:0x382]=b'\x0f\x0b'
    return bytes(data)


def verify_named_callbacks(result,report,root,machine,mode):
    width=8 if machine==0x8664 else 4
    data=image_range(result,root,0x2300,0x100)
    value=lambda n:int.from_bytes(data[n:n+width],'little')
    state=report['kernel_named_callbacks'];objects=state['objects'];regs=state['registrations']
    assert state['callbacks_executed']==0
    if mode in PARTIAL:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        if mode.startswith('api-'):
            assert state['api_denials'] and 'Unmodeled private CALLBACK_OBJECT' in report['entry_points'][0]['error']['context_summary']
        if mode=='notify-active':
            assert 'dispatch of registered guest routines is not modeled' in report['entry_points'][0]['error']['context_summary']
        return
    assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
    if mode in ('missing','unnamed','malformed-name','bad-length','odd-unicode','short-unicode'):
        assert not objects and value(0)==0
        assert value(0x10)=={'missing':0xC0000034,'unnamed':0xC0000001,'malformed-name':0xC0000033,
                            'bad-length':0xC000000D,'odd-unicode':0xC000000D,'short-unicode':0xC000000D}[mode]
        return
    assert len(objects)==1 and value(0)==int(objects[0]['address'],0) and value(0x10)==0
    obj=objects[0];assert obj['permissions']=='---'
    assert value(0)>=(0xFFFF000000000000 if width==8 else 0x80000000)
    if mode.startswith('system-'):
        assert obj['system'] and obj['permanent'] and obj['references']==2
    elif mode in ('reopen','case-insensitive','permanent'):
        assert value(0x20)==value(0) and value(0x28)==0 and obj['references']==2
    elif mode in ('case-sensitive','reopen-deleted'):
        assert value(0x20)==0 and value(0x28)==0xC0000034
        assert obj['live']==(mode=='case-sensitive')
    elif mode=='dereference':assert obj['references']==0 and not obj['live']
    if mode in ('register','duplicate','multiple','unregister'):
        assert value(0x30) and len(regs)==(2 if mode=='multiple' else 1)
        assert obj['references']==(3 if mode=='multiple' else 1 if mode=='unregister' else 2)
        assert all(r['active']==(mode!='unregister') for r in regs)
        if mode=='duplicate':assert value(0x38)==0
        if mode=='multiple':assert value(0x38) and value(0x38)!=value(0x30)
    if mode=='register-invalid':assert value(0x30)==0 and not regs
    if mode=='registration-holds-reference':
        assert obj['references']==0 and not obj['live'] and len(regs)==1 and not regs[0]['active']
        assert [e['references_after'] for e in state['events'] if 'references_after' in e]==[1,2,0]
    if mode=='notify-empty':assert state['events'][-1]['dispatched']==0 and state['events'][-1]['registered']==0


class KernelNamedCallbackTests(unittest.TestCase):
    def probe(self,*modes):
        for machine in (0x14c,0x8664):
            for mode in modes:
                with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                    root=Path(d);payload=named_callback_probe(machine,mode)
                    result=run_driver(payload,inspect_pe(payload,'named-callback.sys'),load_persona(None),root,5,10000)
                    verify_named_callbacks(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode)
    def test_create_missing_and_system_objects(self):self.probe('create','missing','system-power','system-time','system-processor')
    def test_open_identity_case_sensitivity_and_attributes(self):self.probe('reopen','case-sensitive','case-insensitive')
    def test_invalid_names_and_security_are_not_success(self):self.probe('unnamed','malformed-name','security','root','readonly')
    def test_registration_multiple_rule_and_unregister(self):self.probe('register','duplicate','multiple','unregister','unregister-twice','register-invalid')
    def test_notification_does_not_fake_registered_execution(self):self.probe('notify-empty','notify-active','notify-system')
    def test_object_manager_lifetime_and_permanent_namespace(self):self.probe('dereference','reopen-deleted','permanent')
    def test_native_private_body_and_token_permissions(self):self.probe('body-read','body-write','body-call','token-read')
    def test_api_helpers_cannot_expose_private_bodies(self):self.probe('api-read','api-write')
    def test_registration_keeps_object_alive_until_unregister(self):self.probe('registration-holds-reference')
    def test_irql_contracts_stop_before_operation(self):self.probe('irql-create','irql-register','irql-unregister','irql-notify')
    def test_structure_and_unicode_length_validation(self):self.probe('bad-length','odd-unicode','short-unicode')
    def test_import_dynamic_and_native_lookup_agree_for_callback_exports(self):
        for machine in (0x14c,0x8664):
            for name in EXPORTS:
                with self.subTest(machine=machine,name=name),tempfile.TemporaryDirectory() as d:
                    root=Path(d);payload=process_probe(machine,'lookup',name,read_data=False)
                    result=run_driver(payload,inspect_pe(payload,'callback-lookup.sys'),load_persona(None),root,5,10000)
                    report=json.loads((root/'engine-report.json').read_text())
                    data=image_range(result,root,0x2300,0x100);width=8 if machine==0x8664 else 4
                    values=[int.from_bytes(data[n:n+width],'little') for n in (0x10,0x20,0x50)]
                    assert values[0] and len(set(values))==1 and not result['errors'] and result['guest_entry_return']==0
                    assert not report['kernel_named_callbacks']['objects']
