"""Windows utilities called from PowerShell use the same persona and CPU models."""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.dashboard import create_app
from emumee.persona import load_persona
from emumee.powershell import project_trace, run_script, save_script_run
from emumee.powershell_capture import guest_tool_event, docker
from emumee.powershell_guest_tools import program_names, programs

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {
    'arp.exe':['-a'], 'auditpol.exe':['/get','/category:*'], 'bcdedit.exe':['/enum'],
    'cmdkey.exe':['/list'], 'driverquery.exe':['/fo','csv'], 'dsregcmd.exe':['/status'],
    'fltmc.exe':['filters'], 'fsutil.exe':['fsinfo','drives'], 'getmac.exe':[], 'gpresult.exe':['/r'],
    'hostname.exe':[], 'ipconfig.exe':['/all'], 'klist.exe':['tickets'], 'manage-bde.exe':['-status'],
    'mountvol.exe':[], 'net.exe':['user'], 'net1.exe':['user'],
    'netsh.exe':['interface','ipv4','show','config'], 'netstat.exe':['-ano'],
    'nltest.exe':['/domain_trusts'], 'nslookup.exe':['localhost'], 'ping.exe':['-n','1','localhost'],
    'pnputil.exe':['/enum-devices'], 'query.exe':['session'], 'quser.exe':[], 'qwinsta.exe':[],
    'reg.exe':['query',r'HKCU\Control Panel\Desktop','/v','ScreenSaveActive'], 'route.exe':['print','-4'],
    'sc.exe':['query'], 'schtasks.exe':['/query'], 'systeminfo.exe':[], 'tasklist.exe':['/svc'],
    'tzutil.exe':['/g'], 'vssadmin.exe':['list','shadows'], 'w32tm.exe':['/query','/source'],
    'wbadmin.exe':['get','versions'], 'wevtutil.exe':['el'], 'where.exe':['hostname.exe'],
    'whoami.exe':['/all'], 'wmic.exe':['os','get','Version','/value'],
}


def record_event(record):
    return {'event':'guest_tool_record','pid':23,'sequence':17,'data_hex':json.dumps(record).encode().hex()}


class GuestToolTests(unittest.TestCase):
    def record(self):
        return {'event':'guest_windows_enumeration','program':'whoami.exe','arguments':['/user'],
                'persona_sha256':'1'*64,'pe_sha256':'2'*64,'guest_exit_code':0,'architecture':'x64',
                'network_broker_available':False,'network_events':[{'event':'guest_dns_query','capture':'external_linux_ptrace'}],
                'errors':[], 'capture':'external_linux_ptrace','provenance':'kernel_verified','native_arguments':['forged']}

    def test_model_records_cannot_claim_kernel_provenance_and_malformed_records_fail(self):
        record = self.record()
        command, network = guest_tool_event(record_event(record), ['whoami.exe'], '1'*64)
        self.assertEqual(command['capture'], 'guest_windows_emulation')
        self.assertEqual(command['provenance'], 'in_process_data')
        self.assertTrue(command['persona_matches_baseline'])
        self.assertEqual(command['unbound_arguments'], ['/user'])
        self.assertNotIn('native_arguments', command)
        self.assertEqual(network[0]['capture'], 'guest_windows_emulation')
        self.assertFalse(network[0]['network_used'])
        for field, value in (('program','arbitrary.exe'),('arguments','bad'),('arguments',[False]),
                             ('guest_exit_code',True),('persona_sha256','bad'),('network_broker_available',True),
                             ('architecture','x86'),('errors',['x'*2049]),('network_events',[{}])):
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                guest_tool_event(record_event({**record,field:value}), ['whoami.exe'], '1'*64)

    def test_changed_persona_and_missing_model_result_are_visible(self):
        commands, network, console, errors = project_trace([record_event(self.record())],
            guest_tools=['whoami.exe'], persona_sha256='3'*64)
        self.assertFalse(commands[0]['persona_matches_baseline'])
        self.assertTrue(any('persona changed' in e for e in errors))
        native = [{'event':'native_exec_attempt','pid':23,'sequence':1,
                   'path_hex':b'/opt/emumee/bin/whoami.exe'.hex(),
                   'argv_hex':[b'/opt/emumee/bin/whoami.exe'.hex()]},
                  {'event':'native_exec_committed','pid':23,'sequence':2}]
        _,_,_,errors = project_trace(native,guest_tools=['whoami.exe'])
        self.assertTrue(any('did not return a valid emulation record' in e for e in errors))

    def test_persona_document_is_validated_once_and_copied_without_mutation(self):
        document = {'hostname':'LAB-PS-204','user_name':'Sam','cpu':{'cores':4},'clock_utc':'2026-10-14T12:00:00Z'}
        original = copy.deepcopy(document)
        from_document = load_persona(None, document=document)
        self.assertEqual(document, original)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'persona.json'
            path.write_text(json.dumps(document),encoding='utf-8')
            self.assertEqual(from_document,load_persona(path))
        for data in ([], 'bad', {'unexpected':True}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                load_persona(None,document=data)
        with self.assertRaises(ValueError):
            load_persona(Path('unused'),document={})

    def test_inventory_matches_generated_pe_set_and_has_no_host_program_fallback(self):
        self.assertEqual(set(program_names()),set(COMMANDS))
        self.assertTrue(all(p[:2] == b'MZ' for p in programs(load_persona(None)).values()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.ps1'
            path.write_text('whoami.exe',encoding='utf-8')
            with patch('emumee.powershell.docker') as mocked, self.assertRaises(ValueError):
                run_script(path,Path('unused'),Path('unused'),persona_path=Path('persona.json'))
            mocked.assert_not_called()


@unittest.skipUnless(os.environ.get('EMUMEE_POWERSHELL_INTEGRATION')=='1', 'requires trusted guest tools build and Docker Desktop Linux')
class GuestToolContainerTests(unittest.TestCase):
    observer=ROOT/'output/powershell-exec-observer/observer'
    engine=ROOT/'output/powershell-instrumented-engine/System.Management.Automation.dll'
    build=ROOT/'output/powershell-guest-tools/build.json'

    def execute(self,source,override=None,timeout=120):
        with tempfile.TemporaryDirectory() as directory:
            sample=Path(directory)/'input.ps1'
            sample.write_text(source,encoding='utf-8')
            persona=Path(directory)/'persona.json'
            persona.write_text(json.dumps(override or {}),encoding='utf-8')
            report=run_script(sample,self.observer,self.engine,guest_tools_build=self.build,
                              persona_path=persona,timeout=timeout)
        self.assertEqual(docker('ps','-aq','--filter','name=emumee-powershell-').strip(),'')
        run=save_script_run(report,ROOT/'output/powershell-persona-gate')
        return report,run

    def test_all_40_tools_emulate_from_powershell_with_one_custom_persona(self):
        override={'hostname':'LAB-PS-204','user_name':'Sam','user_is_admin':True,'domain':'corp.example',
                  'device_registration':{'domain_joined':True},'clock_utc':'2026-10-14T12:00:00Z',
                  'network_adapter':{'ipv4':'192.0.2.77','gateway':'192.0.2.1','dns_servers':['192.0.2.53']}}
        source=["$ErrorActionPreference='Stop'"]
        for name,args in COMMANDS.items():
            command = 'WhOaMi.ExE' if name=='whoami.exe' else name
            if name=='hostname.exe': command=r'C:\Windows\System32\hostname.exe'
            if name=='wmic.exe': command=r'C:\Windows\System32\Wbem\wmic.exe'
            quoted = ','.join("'"+a.replace("'","''")+"'" for a in args)
            source.append(f"& '{command}' @({quoted}) | Out-Null")
            source.append(f"if ($LASTEXITCODE -ne 0) {{ throw '{name} failed' }}")
        source.extend(["$p=Start-Process '/opt/emumee/bin/whoami.exe' -ArgumentList '/user' -Wait -PassThru -NoNewWindow", "if ($p.ExitCode -ne 0) { throw 'Start-Process failed' }", "Write-Output ('all-programs-completed=' + $env:COMPUTERNAME)"])
        report,run=self.execute('\n'.join(source),override,timeout=240)
        self.assertEqual(report['errors'],[])
        self.assertEqual(report['guest_exit_code'],0)
        self.assertTrue(report['observer_trace_complete'])
        self.assertTrue(all(report['configuration_checks'].values()))
        models=[c for c in report['command_events'] if c['capture']=='guest_windows_emulation']
        self.assertEqual(set(c['command'] for c in models),set(COMMANDS))
        self.assertEqual(len(models),41)
        images=programs(load_persona(None,document=override))
        for model in models:
            self.assertTrue(model['persona_matches_baseline'],model)
            self.assertEqual(model['reported_guest_exit_code'],0,model)
            self.assertEqual(model['pe_sha256'],hashlib.sha256(images[model['command']]).hexdigest())
        self.assertIn('all-programs-completed=LAB-PS-204',report['console_output']['stdout'])
        self.assertTrue(any(c.get('path')=='/opt/emumee-python/bin/python' for c in report['command_events']))
        self.assertTrue(any(e['event']=='guest_icmp_echo' and not e['network_used'] for e in report['network_events']))

    def test_identity_registry_dns_ping_environment_and_invalid_arguments(self):
        source=(ROOT/'examples/powershell-persona.ps1').read_text(encoding='utf-8')
        source += "\n& 'IPCONFIG.EXE' '/unsupported'; if ($LASTEXITCODE -ne 87) { throw 'Expected error 87' }; Write-Output ('domain=' + $env:USERDOMAIN)"
        report,run=self.execute(source,{'hostname':'CHECK-PS-501','user_name':'Taylor',
                                      'network_adapter':{'ipv4':'192.168.1.199'}})
        self.assertEqual(report['errors'],[])
        text=report['console_output']['stdout']
        for value in ('CHECK-PS-501\\Taylor','192.168.1.199','ScreenSaveActive','127.0.0.1','persona-host=CHECK-PS-501','domain=CHECK-PS-501'):
            self.assertIn(value,text)
        models=[c for c in report['command_events'] if c['capture']=='guest_windows_emulation']
        self.assertTrue(any(c['command']=='ipconfig.exe' and c['reported_guest_exit_code']==87 for c in models))
        self.assertTrue(all(c['persona_matches_baseline'] for c in models))
        app=create_app(run.parent)
        pages=''.join(app.test_client().get(f'/runs/{run.name}?commands_page={p}').get_data(as_text=True) for p in (1,2))
        for value in ('guest_windows_emulation','CHECK-PS-501','guest_icmp_echo','Reported Windows exit'):
            self.assertIn(value,pages)

    def test_model_persona_mutation_is_flagged_and_full_windows_exit_is_retained(self):
        source=r'''
$ErrorActionPreference='Stop'
nltest.exe /dsgetdc:WORKGROUP | Out-Null
if ($LASTEXITCODE -ne 75) { throw 'Expected low byte of 1355' }
& '/bin/chmod' 'u+w' '/work/persona.json'
$p=[IO.File]::ReadAllText('/work/persona.json') | ConvertFrom-Json
$p.hostname='CHANGED-PS'
[IO.File]::WriteAllText('/work/persona.json',($p | ConvertTo-Json -Depth 100))
whoami.exe
'''
        report,run=self.execute(source)
        self.assertTrue(any('persona changed' in e for e in report['errors']))
        models=[c for c in report['command_events'] if c['capture']=='guest_windows_emulation']
        self.assertEqual(models[0]['reported_guest_exit_code'],1355)
        self.assertTrue(models[0]['persona_matches_baseline'])
        self.assertFalse(models[-1]['persona_matches_baseline'])
        self.assertIn('CHANGED-PS\\Alex',report['console_output']['stdout'])


if __name__=='__main__':
    unittest.main()
