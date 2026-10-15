"""Method payload validation, provenance, and readable dashboard values."""

import copy
import html
import json
import tempfile
import unittest
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell_capture import engine_command_events
from emumee.powershell_probe_report import save_probe_run
from tests.test_command_dashboard import probe_report


def record():
    return {'event':'powershell_command_invocation','sequence':1,'command':'System.String::Concat',
            'phase':'method_arguments_bound','command_type':'DotNetMethod','bound_parameters':{},
            'method_name':'Concat','declaring_type':'System.String','method_signature':'System.String::Concat(System.String, System.String)',
            'dispatch_route':'Ordinary','is_static':True,'is_constructor':False,'metadata_captured':True,
            'target_type':None,'generic_arguments':[],'arguments_truncated':False,
            'method_arguments':[{'position':i,'name':name,'parameter_type':'System.String','by_ref':False,
                                 'is_out':False,'is_optional':False,'value':value}
                                for i,(name,value) in enumerate([('str0','readable café 日本語 😀 <script>alert(1)</script>'),('str1','')])]}


def envelope(value):
    return {'event':'guest_engine_record','pid':17,'sequence':12,'data_hex':json.dumps(value).encode().hex()}


class PowerShellMethodTests(unittest.TestCase):
    def test_method_records_preserve_order_and_cannot_claim_kernel_provenance(self):
        value=record()
        value.update(capture='external_linux_ptrace',provenance='kernel_verified',native_arguments=['forged'])
        parsed=engine_command_events([envelope(value)])[0]
        self.assertEqual(parsed['capture'],'guest_engine_instrumentation')
        self.assertEqual(parsed['provenance'],'in_process_data')
        self.assertNotIn('native_arguments',parsed)
        self.assertEqual(parsed['method_arguments'],value['method_arguments'])
        value['phase']='reflection_arguments_supplied'
        self.assertEqual(engine_command_events([envelope(value)])[0]['phase'],'reflection_arguments_supplied')

    def test_malformed_method_shapes_are_rejected_before_dashboard_rendering(self):
        invalid=[{**record(),'method_arguments':'text'}, {**record(),'phase':'command_line_bound'},
                 {**record(),'is_static':'yes'}, {**record(),'generic_arguments':{}},
                 {**record(),'method_arguments':[record()['method_arguments'][0]]*33}]
        for field,value in (('position',True),('name',None),('by_ref',1),('is_out',None)):
            item=copy.deepcopy(record());item['method_arguments'][0][field]=value;invalid.append(item)
        item=copy.deepcopy(record());del item['method_arguments'][0]['value'];invalid.append(item)
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(ValueError): engine_command_events([envelope(value)])

    def test_dashboard_shows_method_signature_ordered_values_and_reflection_scope(self):
        value=record()
        value['phase']='reflection_arguments_supplied'
        parsed=engine_command_events([envelope(value)])[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            run=save_probe_run(probe_report([parsed]),root,'benign method fixture')
            response=create_app(root).test_client().get(f'/runs/{run.name}')
            self.assertEqual(response.status_code,200)
            markup=response.get_data(as_text=True)
            self.assertNotIn('<script>alert(1)</script>',markup)
            rendered=html.unescape(markup)
            for value in ('Resolved .NET method',parsed['method_signature'],'Passed method arguments','readable café 日本語 😀','""',
                          'before CLR reflection conversion', 'does not establish successful invocation'):
                self.assertIn(value,rendered)
